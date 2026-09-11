"""Exercise Images API requests against the Rust test's local gateway fixture."""

import base64
import sys
from urllib.parse import urlsplit

from openai import OpenAI

base_url = sys.argv[1]
url = urlsplit(base_url)
if url.scheme != "http" or url.hostname != "127.0.0.1":
    raise ValueError("the SDK smoke test requires the local Rust fixture")

png = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aZV8AAAAASUVORK5CYII="
)
with OpenAI(base_url=base_url, api_key="local-fixture", max_retries=0, timeout=10) as client:
    generated = client.images.generate(model="gpt-image-2", prompt="a blue square", quality="low")
    assert generated.data[0].b64_json == "aW1hZ2U="
    edited = client.images.edit(
        model="gpt-image-2",
        prompt="make it blue",
        image=[("first.png", png, "image/png"), ("second.png", png, "image/png")],
        mask=("mask.png", png, "image/png"),
        n=1,
    )
    assert edited.data[0].b64_json == "aW1hZ2U="
